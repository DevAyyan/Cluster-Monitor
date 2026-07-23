package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type FleetJob struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "fetch_metrics", "fetch_processes", "fetch_storage", "fetch_containers"
	ServerID string `json:"server_id"`
}

const (
	fleetQueueKey    = "bull:fleet-jobs:queue"
	maxQueueCapacity = 100 // Prevent queue bloat
)

var (
	inFlightJobsMu sync.Mutex
	inFlightJobs   = make(map[string]time.Time)
)

// EnqueueJob pushes a job to Redis queue (RPUSH)
func (r *RedisClient) EnqueueJob(job FleetJob) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}

	data, err := json.Marshal(job)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Check queue length to avoid unbounded growth
	qLen, err := r.client.LLen(ctx, fleetQueueKey).Result()
	if err == nil && qLen > maxQueueCapacity {
		return fmt.Errorf("redis queue full (%d jobs), skipping enqueue", qLen)
	}

	return r.client.RPush(ctx, fleetQueueKey, string(data)).Err()
}

// DequeueJob pops a job from Redis queue with timeout (BLPOP)
func (r *RedisClient) DequeueJob(timeoutSec int) (*FleetJob, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("redis client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+1)*time.Second)
	defer cancel()

	res, err := r.client.BLPop(ctx, time.Duration(timeoutSec)*time.Second, fleetQueueKey).Result()
	if err != nil {
		if err == redis.Nil || ctx.Err() != nil {
			return nil, nil // timeout / no job
		}
		return nil, err
	}

	if len(res) < 2 {
		return nil, nil
	}

	var job FleetJob
	if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// startBackgroundWorkerPool initializes the background producer and consumer worker pool
func startBackgroundWorkerPool() {
	log.Printf("[bullmq-worker] Starting Redis background worker queue & worker pool...")

	// Producer loop: enqueues background jobs every 8 seconds for all servers
	go func() {
		for {
			enqueueAllServerJobs()
			time.Sleep(8 * time.Second)
		}
	}()

	// Worker Pool: 4 worker goroutines processing jobs concurrently from Redis queue
	for i := 1; i <= 4; i++ {
		workerID := i
		go func(id int) {
			for {
				if globalRedis == nil {
					time.Sleep(1 * time.Second)
					continue
				}
				job, err := globalRedis.DequeueJob(2)
				if err != nil || job == nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}

				// Mark job in-flight
				jobKey := fmt.Sprintf("%s:%s", job.ServerID, job.Type)
				inFlightJobsMu.Lock()
				inFlightJobs[jobKey] = time.Now()
				inFlightJobsMu.Unlock()

				processFleetJob(id, *job)

				// Clear job in-flight mark
				inFlightJobsMu.Lock()
				delete(inFlightJobs, jobKey)
				inFlightJobsMu.Unlock()
			}
		}(workerID)
	}
}

func enqueueAllServerJobs() {
	if db == nil || globalRedis == nil {
		return
	}
	rows, err := db.Query("SELECT id FROM servers WHERE status != 'offline'")
	if err != nil {
		// Fallback to all servers if query fails
		rows, err = db.Query("SELECT id FROM servers")
		if err != nil {
			return
		}
	}
	defer rows.Close()

	now := time.Now()
	inFlightJobsMu.Lock()
	// Clean up stale in-flight jobs older than 30s
	for k, t := range inFlightJobs {
		if now.Sub(t) > 30*time.Second {
			delete(inFlightJobs, k)
		}
	}

	jobTypes := []string{"fetch_metrics", "fetch_processes", "fetch_storage", "fetch_containers"}

	for rows.Next() {
		var sID string
		if err := rows.Scan(&sID); err == nil {
			for _, jType := range jobTypes {
				jobKey := fmt.Sprintf("%s:%s", sID, jType)
				if _, inFlight := inFlightJobs[jobKey]; !inFlight {
					_ = globalRedis.EnqueueJob(FleetJob{
						ID:       fmt.Sprintf("%s-%s-%d", sID, jType, now.Unix()),
						Type:     jType,
						ServerID: sID,
					})
				}
			}
		}
	}
	inFlightJobsMu.Unlock()
}

func processFleetJob(workerID int, job FleetJob) {
	info, err := loadServerSSHInfo(job.ServerID)
	if err != nil {
		return
	}

	switch job.Type {
	case "fetch_metrics":
		if isDemoServer(info, job.ServerID) {
			randVal := func(min, max float64) float64 {
				return min + float64(time.Now().UnixNano()%int64(max-min))
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
			setCachedMetrics(job.ServerID, m, 60)
		} else {
			m, err := sshGetMetrics(info)
			if err == nil {
				setCachedMetrics(job.ServerID, m, 60)
				persistMetricSample(job.ServerID, m)
				_, _ = db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", job.ServerID)
			} else {
				// Server unreachable — update status to offline in DB if last_seen > 15s ago
				var lastSeen time.Time
				_ = db.QueryRow("SELECT last_seen FROM servers WHERE id = $1", job.ServerID).Scan(&lastSeen)
				if time.Since(lastSeen) > 15*time.Second {
					_, _ = db.Exec("UPDATE servers SET status = 'offline' WHERE id = $1", job.ServerID)
				}
			}
		}

	case "fetch_processes":
		if isDemoServer(info, job.ServerID) {
			mockProcs := []map[string]interface{}{
				{"pid": "1", "name": "systemd", "user": "root", "cpu": "0.1", "mem": "12.4"},
				{"pid": "824", "name": "alloy", "user": "alloy", "cpu": "1.2", "mem": "64.8"},
				{"pid": "912", "name": "cluster-agent", "user": "root", "cpu": "0.5", "mem": "18.2"},
				{"pid": "1042", "name": "postgres", "user": "postgres", "cpu": "0.8", "mem": "142.1"},
				{"pid": "1205", "name": "nginx", "user": "nginx", "cpu": "0.2", "mem": "8.5"},
				{"pid": "1530", "name": "go-backend", "user": "root", "cpu": "2.4", "mem": "32.0"},
				{"pid": "2054", "name": "node_exporter", "user": "prometheus", "cpu": "0.4", "mem": "14.1"},
				{"pid": "2100", "name": "loki", "user": "loki", "cpu": "1.5", "mem": "98.3"},
			}
			setCachedJSON("processes:"+job.ServerID, mockProcs, 60)
		} else {
			procs, err := sshGetProcesses(info)
			if err == nil {
				setCachedJSON("processes:"+job.ServerID, procs, 60)
			}
		}

	case "fetch_storage":
		if isDemoServer(info, job.ServerID) {
			mockStorage := []map[string]interface{}{
				{"name": "sda1", "size": "80G", "type": "part", "fstype": "ext4", "mountpoint": "/", "model": "Demo Disk"},
				{"name": "sdb1", "size": "200G", "type": "part", "fstype": "ext4", "mountpoint": "/home", "model": ""},
			}
			setCachedJSON("storage:"+job.ServerID, mockStorage, 60)
		} else {
			parts, err := sshGetStorage(info)
			if err == nil {
				setCachedJSON("storage:"+job.ServerID, parts, 60)
			}
		}

	case "fetch_containers":
		if !isDemoServer(info, job.ServerID) {
			containers, err := sshGetContainers(info)
			if err == nil {
				setCachedJSON("containers:"+job.ServerID, containers, 60)
			}
		}
	}
}
