package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Cart struct {
	Id       primitive.ObjectID `bson:"_id,omitempty"`
	Name     string             `bson:"name,omitempty"`
	Price    float32            `bson:"price,omitempty"`
	Quantity int                `bson:"quantity,omitempty"`

	// image url de olsa guzel olur
}
