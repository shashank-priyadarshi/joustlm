package db

func TableNames() map[string]string {
	return map[string]string{
		"User":     "users",
		"Analysis": "analyses",
	}
}

func AllModels() []interface{} {
	return []interface{}{
		&User{},
		&Analysis{},
	}
}
