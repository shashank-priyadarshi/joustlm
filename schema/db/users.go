package db

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID      `json:"id" db:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Username     string         `json:"username" db:"username" gorm:"type:varchar(50);uniqueIndex;not null"`
	PasswordHash string         `json:"-" db:"password_hash" gorm:"type:varchar(255);not null"`
	SessionID    sql.NullString `json:"-" db:"session_id" gorm:"type:varchar(255);index"`
	CreatedAt    time.Time      `json:"created_at" db:"created_at" gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt    time.Time      `json:"updated_at" db:"updated_at" gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP"`
}

func (User) TableName() string {
	return "users"
}
