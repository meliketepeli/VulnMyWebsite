package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// dto amacı

type Product struct {
	Id          primitive.ObjectID `bson:"_id,omitempty"`
	Name        string             `bson:"name,omitempty"`
	Description string             `bson:"description,omitempty"`
	Price       float32            `bson:"price,omitempty"`
	ImageURL    string             `bson:"image_url,omitempty"`
	Quantity    int                `bson:"quantity,omitempty"`
}
