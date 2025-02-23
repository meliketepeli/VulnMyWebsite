package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// dto amacı

type User struct {
	Id       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"name,omitempty"`
	Password string             `bson:"Password,omitempty"`
	Role     string             `bson:"role,omitempty"`
}
