package scheduler

import (
	"fmt"
	"time"

	"github.com/ark-network/ark/server/internal/core/ports"
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

func (s *service) ScheduleTask(interval int64, immediate bool, task func()) error {
	if immediate {
		_, err := s.scheduler.Every(int(interval)).Seconds().Do(task)
		return err
	}
	_, err := s.scheduler.Every(int(interval)).Seconds().WaitForSchedule().Do(task)
	return err
}

func (s *service) ScheduleTaskOnce(at int64, task func()) error {
	delay := at - time.Now().Unix()
	if delay < 0 {
		return fmt.Errorf("cannot schedule task in the past")
	}

	_, err := s.scheduler.Every(int(delay)).Seconds().WaitForSchedule().LimitRunsTo(1).Do(task)
	return err
}
