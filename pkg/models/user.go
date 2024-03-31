package models

type User struct {
	ID             int    `json:"id"`
	FullName       string `json:"name"`
	Email          string `json:"email" gorm:"unique"`
	HashedPassword string `json:"-"`
	Role           string `json:"role"`
}
