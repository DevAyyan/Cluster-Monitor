package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
}

var globalRedis *RedisClient

const defaultCacheTTL = 60 // Cache stays valid for 60s or until fresh data arrives from target

func initRedis() {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}
	addr := net.JoinHostPort(host, port)

	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
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
	} else {
		log.Printf("[redis] Successfully connected Redis client to %s (pooled)", addr)
	}

	globalRedis = &RedisClient{
		client: rdb,
	}
}

func (r *RedisClient) Get(key string) (string, error) {
	if r == nil || r.client == nil {
		return "", fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil // cache miss
	}
	return val, err
}

func (r *RedisClient) Del(key string) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return r.client.Del(ctx, key).Err()
}

func (r *RedisClient) SetEX(key string, value string, seconds int) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return r.client.Set(ctx, key, value, time.Duration(seconds)*time.Second).Err()
}

func (r *RedisClient) Publish(channel string, message string) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	return r.client.Publish(ctx, channel, message).Err()
}

// Generic JSON cache helpers
func getCachedJSON(key string) (string, bool) {
	if globalRedis == nil {
		return "", false
	}
	val, err := globalRedis.Get(key)
	if err != nil || val == "" {
		return "", false
	}
	return val, true
}

func setCachedJSON(key string, data interface{}, seconds int) {
	if globalRedis == nil {
		return
	}
	if seconds <= 0 {
		seconds = defaultCacheTTL
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	_ = globalRedis.SetEX(key, string(b), seconds)
}

// Helpers for metric caching
func getCachedMetrics(serverID string) (map[string]interface{}, bool) {
	val, ok := getCachedJSON("metrics:" + serverID)
	if !ok {
		return nil, false
	}
	var metrics map[string]interface{}
	if err := json.Unmarshal([]byte(val), &metrics); err != nil {
		return nil, false
	}
	return metrics, true
}

func setCachedMetrics(serverID string, metrics map[string]interface{}, seconds int) {
	setCachedJSON("metrics:"+serverID, metrics, seconds)
}
