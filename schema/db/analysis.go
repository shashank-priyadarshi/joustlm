package db

import (
	"time"

	"github.com/google/uuid"
)


type Analysis struct {
	ID          uuid.UUID `json:"id" db:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid();not null;index"`
	UserID      uuid.UUID `json:"user_id" db:"user_id" gorm:"type:uuid;not null;index;foreignKey:UserID;references:ID"`
	Text        string    `json:"text" db:"text" gorm:"type:text;not null"`
	Title       string    `json:"title" db:"title" gorm:"type:text"`
	Summary     string    `json:"summary" db:"summary" gorm:"type:text"`
	Topics      string    `json:"topics" db:"topics" gorm:"type:text"`      // JSON array of 3 key topics
	Sentiment   string    `json:"sentiment" db:"sentiment" gorm:"type:varchar(20)"` // positive/neutral/negative
	Keywords    string    `json:"keywords" db:"keywords" gorm:"type:text"`   // JSON array of 3 most frequent nouns
	Confidence  float64   `json:"confidence" db:"confidence" gorm:"type:real"`
	CreatedAt   time.Time `json:"created_at" db:"created_at" gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at" gorm:"type:timestamp;not null;default:CURRENT_TIMESTAMP"`
	User        *User     `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID;not null"`
}

func (Analysis) TableName() string {
	return "analyses"
}
