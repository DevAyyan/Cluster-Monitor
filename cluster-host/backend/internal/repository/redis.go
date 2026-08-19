package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"cluster-backend/internal/config"
)

type RedisClient struct {
	Client *redis.Client
}

const DefaultCacheTTL = 60 // Cache stays valid for 60s or until fresh data arrives from target

func NewRedis(cfg *config.Config) (*RedisClient, error) {
	addr := net.JoinHostPort(cfg.RedisHost, cfg.RedisPort)

	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     cfg.RedisPassword,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     20,
		MinIdleConns: 5,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("[redis] Warning: Redis ping failed for %s: %v", addr, err)
		return &RedisClient{Client: rdb}, err
	}

	log.Printf("[redis] Successfully connected Redis client to %s (pooled)", addr)
	return &RedisClient{Client: rdb}, nil
}

func (r *RedisClient) Get(key string) (string, error) {
	if r == nil || r.Client == nil {
		return "", fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	val, err := r.Client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // cache miss
	}
	return val, err
}

func (r *RedisClient) Del(key string) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return r.Client.Del(ctx, key).Err()
}

func (r *RedisClient) SetEX(key string, value string, seconds int) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return r.Client.Set(ctx, key, value, time.Duration(seconds)*time.Second).Err()
}

func (r *RedisClient) Publish(channel string, message string) error {
	if r == nil || r.Client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return r.Client.Publish(ctx, channel, message).Err()
}

func (r *RedisClient) GetCachedJSON(key string) (string, bool) {
	val, err := r.Get(key)
	if err != nil || val == "" {
		return "", false
	}
	return val, true
}

func (r *RedisClient) SetCachedJSON(key string, data interface{}, seconds int) {
	if seconds <= 0 {
		seconds = DefaultCacheTTL
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	_ = r.SetEX(key, string(b), seconds)
}

func (r *RedisClient) GetCachedMetrics(serverID string) (map[string]interface{}, bool) {
	val, ok := r.GetCachedJSON("metrics:" + serverID)
	if !ok {
		return nil, false
	}
	var metrics map[string]interface{}
	if err := json.Unmarshal([]byte(val), &metrics); err != nil {
		return nil, false
	}
	return metrics, true
}

func (r *RedisClient) SetCachedMetrics(serverID string, metrics map[string]interface{}, seconds int) {
	r.SetCachedJSON("metrics:"+serverID, metrics, seconds)
	r.PublishMetricStream(serverID, metrics)
}

func (r *RedisClient) PublishMetricStream(serverID string, metrics map[string]interface{}) {
	payload := map[string]interface{}{
		"server_id": serverID,
		"metrics":   metrics,
		"timestamp": time.Now().Unix(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = r.Publish("metrics_stream_global", string(b))
	_ = r.Publish("metrics_stream:"+serverID, string(b))
}
