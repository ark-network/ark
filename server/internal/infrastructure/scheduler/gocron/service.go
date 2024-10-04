package timescheduler

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

func (s *service) Unit() ports.TimeUnit {
	return ports.UnixTime
}

func (s *service) AddNow(lifetime int64) int64 {
	return time.Now().Add(time.Duration(lifetime) * time.Second).Unix()
}

func (s *service) AfterNow(expiry int64) bool {
	return time.Unix(expiry, 0).After(time.Now())
}

func (s *service) Start() {
	s.scheduler.StartAsync()
}

func (s *service) Stop() {
	s.scheduler.Stop()
}

func (s *service) ScheduleTaskOnce(at int64, task func()) error {
	delay := at - time.Now().Unix()
	if delay < 0 {
		return fmt.Errorf("cannot schedule task in the past")
	}

	_, err := s.scheduler.Every(int(delay)).Seconds().WaitForSchedule().LimitRunsTo(1).Do(task)
	return err
}
