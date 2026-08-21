package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"cluster-backend/internal/domain"
	"cluster-backend/internal/repository"
	"cluster-backend/internal/ssh"
	"cluster-backend/internal/websocket"
)

const (
	fleetQueueKey    = "bull:fleet-jobs:queue"
	maxQueueCapacity = 100
)

type WorkerPool struct {
	db           *sql.DB
	redis        *repository.RedisClient
	encKey       string
	inFlight     map[string]time.Time
	inFlightMu   sync.Mutex
}

func NewWorkerPool(db *sql.DB, redis *repository.RedisClient, encKey string) *WorkerPool {
	return &WorkerPool{
		db:         db,
		redis:      redis,
		encKey:     encKey,
		inFlight:   make(map[string]time.Time),
	}
}

func (wp *WorkerPool) EnqueueJob(job domain.FleetJob) error {
	if wp.redis == nil || wp.redis.Client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	data, err := json.Marshal(job)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	qLen, err := wp.redis.Client.LLen(ctx, fleetQueueKey).Result()
	if err == nil && qLen > maxQueueCapacity {
		return fmt.Errorf("redis queue full (%d jobs), skipping enqueue", qLen)
	}

	return wp.redis.Client.RPush(ctx, fleetQueueKey, string(data)).Err()
}

func (wp *WorkerPool) DequeueJob(timeoutSec int) (*domain.FleetJob, error) {
	if wp.redis == nil || wp.redis.Client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+1)*time.Second)
	defer cancel()

	res, err := wp.redis.Client.BLPop(ctx, time.Duration(timeoutSec)*time.Second, fleetQueueKey).Result()
	if err != nil {
		if err == redis.Nil || ctx.Err() != nil {
			return nil, nil
		}
		return nil, err
	}

	if len(res) < 2 {
		return nil, nil
	}

	var job domain.FleetJob
	if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (wp *WorkerPool) Start() {
	log.Printf("[worker-pool] Starting Redis background worker queue & worker pool...")

	// Producer loop: enqueues background jobs every 8s for servers needing SSH polling
	go func() {
		for {
			wp.enqueueAllServerJobs()
			time.Sleep(8 * time.Second)
		}
	}()

	// Consumer pool: 4 worker goroutines processing jobs concurrently
	for i := 1; i <= 4; i++ {
		workerID := i
		go func(id int) {
			for {
				if wp.redis == nil {
					time.Sleep(1 * time.Second)
					continue
				}
				job, err := wp.DequeueJob(2)
				if err != nil || job == nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}

				jobKey := fmt.Sprintf("%s:%s", job.ServerID, job.Type)
				wp.inFlightMu.Lock()
				wp.inFlight[jobKey] = time.Now()
				wp.inFlightMu.Unlock()

				wp.processFleetJob(id, *job)

				wp.inFlightMu.Lock()
				delete(wp.inFlight, jobKey)
				wp.inFlightMu.Unlock()
			}
		}(workerID)
	}
}

func (wp *WorkerPool) enqueueAllServerJobs() {
	if wp.db == nil || wp.redis == nil {
		return
	}
	rows, err := wp.db.Query("SELECT id FROM servers WHERE status != 'offline'")
	if err != nil {
		rows, err = wp.db.Query("SELECT id FROM servers")
		if err != nil {
			return
		}
	}
	defer rows.Close()

	now := time.Now()
	wp.inFlightMu.Lock()
	for k, t := range wp.inFlight {
		if now.Sub(t) > 30*time.Second {
			delete(wp.inFlight, k)
		}
	}

	jobTypes := []string{"fetch_metrics", "fetch_processes", "fetch_storage", "fetch_containers"}

	for rows.Next() {
		var sID string
		if err := rows.Scan(&sID); err == nil {
			// Dynamic Fallback: Skip SSH queue jobs if agent is actively streaming over WebSocket!
			if websocket.Manager.IsConnected(sID) {
				continue
			}

			for _, jType := range jobTypes {
				jobKey := fmt.Sprintf("%s:%s", sID, jType)
				if _, inFlight := wp.inFlight[jobKey]; !inFlight {
					_ = wp.EnqueueJob(domain.FleetJob{
						ID:       fmt.Sprintf("%s-%s-%d", sID, jType, now.Unix()),
						Type:     jType,
						ServerID: sID,
					})
				}
			}
		}
	}
	wp.inFlightMu.Unlock()
}

func (wp *WorkerPool) processFleetJob(workerID int, job domain.FleetJob) {
	info, err := ssh.LoadServerSSHInfo(wp.db, wp.encKey, job.ServerID)
	if err != nil {
		return
	}

	switch job.Type {
	case "fetch_metrics":
		if ssh.IsDemoServer(info, job.ServerID) {
			randVal := func(min, max float64) float64 {
				return min + rand.Float64()*(max-min)
			}
			m := map[string]interface{}{
				"cpu":           randVal(15, 65),
				"ram_used_pct":  randVal(30, 70),
				"ram_used_gb":   8.0 * (randVal(30, 70) / 100.0),
				"ram_total_gb":  8.0,
				"swap_used_pct": randVal(5, 15),
				"swap_used_gb":  2.0 * (randVal(5, 15) / 100.0),
				"swap_total_gb": 2.0,
				"disk_used_pct": 48.0,
				"disk_used_gb":  250.0 * 0.48,
				"disk_total_gb": 250.0,
				"net_rx_kb":     randVal(10, 250),
				"net_tx_kb":     randVal(5, 80),
				"cores":         []float64{randVal(10, 80), randVal(10, 80), randVal(10, 80), randVal(10, 80)},
			}
			wp.redis.SetCachedMetrics(job.ServerID, m, 60)
		} else {
			m, err := ssh.SSHGetMetrics(info)
			if err == nil {
				wp.redis.SetCachedMetrics(job.ServerID, m, 60)
				_, _ = wp.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", job.ServerID)
			} else {
				var lastSeen time.Time
				_ = wp.db.QueryRow("SELECT last_seen FROM servers WHERE id = $1", job.ServerID).Scan(&lastSeen)
				if time.Since(lastSeen) > 15*time.Second {
					_, _ = wp.db.Exec("UPDATE servers SET status = 'offline' WHERE id = $1", job.ServerID)
				}
			}
		}

	case "fetch_processes":
		if !ssh.IsDemoServer(info, job.ServerID) {
			procs, err := ssh.SSHGetProcesses(info)
			if err == nil {
				wp.redis.SetCachedJSON("processes:"+job.ServerID, procs, 60)
			}
		}

	case "fetch_storage":
		if !ssh.IsDemoServer(info, job.ServerID) {
			parts, err := ssh.SSHGetStorage(info)
			if err == nil {
				wp.redis.SetCachedJSON("storage:"+job.ServerID, parts, 60)
			}
		}

	case "fetch_containers":
		if !ssh.IsDemoServer(info, job.ServerID) {
			conts, err := ssh.SSHGetContainers(info)
			if err == nil && conts != nil {
				wp.redis.SetCachedJSON("containers:"+job.ServerID, conts, 60)
			}
		}
	}
}
