package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Order struct {
	Id       primitive.ObjectID ` bson:"_id,omitempty"`
	Name     string             `bson:"name"`
	Price    float64            ` bson:"price"`
	Quantity int                ` bson:"quantity"`
}
