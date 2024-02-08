package ports

type SchedulerService interface {
	Start()
	Stop()

	ScheduleTask(interval int64, immediate bool, task func()) error
	ScheduleTaskOnce(delay int64, task func()) error
}
