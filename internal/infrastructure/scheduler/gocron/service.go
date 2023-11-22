package scheduler

import (
	"time"

	"github.com/ark-network/ark/internal/core/ports"
	"github.com/go-co-op/gocron"
)

type service struct {
	scheduler *gocron.Scheduler
}

func NewScheduler() ports.SchedulerService {
	svc := gocron.NewScheduler(time.UTC)
	return &service{svc}
}

func (s *service) Start() {
	s.scheduler.StartAsync()
}

func (s *service) Stop() {
	s.scheduler.Stop()
}

func (s *service) ScheduleTask(interval int64, immediate bool, task func()) {
	if immediate {
		s.scheduler.Every(interval).Seconds().Do(task)
		return
	}
	s.scheduler.Every(interval).Seconds().WaitForSchedule().Do(task)
}
