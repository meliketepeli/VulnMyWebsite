package repository

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"myWebsite-main/models"
	"time"
)

type UserRepositoryDB struct {
	UserCollection *mongo.Collection
	// buradan ekleme silme guncelleme gibi islemleri yapacagız
}

type UserRepository interface {
	Insert(user models.User) (bool, error)
	//bool yerine string de olabilir

	// tum verileri almak için bir fonksiyon oluşturduk ve bu fonksiyon array olmalı
	GetAll() ([]models.User, error)

	//delete oluşturuyoruz
	Delete(id primitive.ObjectID) (bool, error)
	

	FindOne(ctx context.Context, filter bson.M) (*models.User, error) // 🔴 NoSQL Injection
}

type DefaultUserRepository struct {
	Collection *mongo.Collection
}

func (r DefaultUserRepository) Insert(user models.User) (bool, error) {
	_, err := r.Collection.InsertOne(context.TODO(), user)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (u *UserRepositoryDB) Insert(user models.User) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// düşün bir kanal acmışsın
	//10 saniye bağlanmayı dene demek
	defer cancel()
	// en son defer calısır

	user.Id = primitive.NewObjectID()
	// bunu farklı object id versin diye yazdık generate etsin

	result, err := u.UserCollection.InsertOne(ctx, user)

	if err != nil || result.InsertedID == nil {
		errors.New("Failed to insert user")
		return false, err
	}
	log.Println("Başarılı şekilde user eklendi eklenen user : ", user)
	return true, nil
}

func (r DefaultUserRepository) GetAll() ([]models.User, error) {
	cursor, err := r.Collection.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}

	var users []models.User
	if err := cursor.All(context.TODO(), &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (u *UserRepositoryDB) GetAll() ([]models.User, error) {

	var user models.User    // bir eleman
	var users []models.User // birden fazla
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// baglantı actık
	defer cancel()

	result, err := u.UserCollection.Find(ctx, bson.M{})
	// açtığım yolu verdim, result a aldıgım dokumanları verdim

	if err != nil {
		//log.Fatalln(err)
		log.Println("MongoDB'den kullanıcı verisi alınırken hata oluştu:", err)
		return nil, err

	}

	// tek tek bu verdiğim dokumanları almam lazım!!!
	// tekrar baglantı yolunu actım
	for result.Next(ctx) {
		// eger documentta decode edebilecegim bir sey varsa decodela, user a ata
		if err := result.Decode(&user); err != nil {
			// log.Fatalln(err)
			log.Println("Document decode edilirken hata oluştu:", err)
			return nil, err
		}
		// eger decode gerek yoksa ekle
		users = append(users, user)

	}
	// Döngü sonunda, eğer hata varsa onu döndürelim
	if err := result.Err(); err != nil {
		log.Println("Döngü sırasında hata oluştu:", err)
		return nil, err
	}

	log.Println("Başarıyla eklenen users:", users)
	return users, nil
}

func (u *UserRepositoryDB) Delete(id primitive.ObjectID) (bool, error) {

	// once bir kanal oluşturuyoruz
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := u.UserCollection.DeleteOne(ctx, bson.M{"id": id})

	if err != nil || result.DeletedCount <= 0 {
		return false, err
	}
	return true, nil
}

func (r DefaultUserRepository) Delete(id string) (bool, error) {
	filter := bson.M{"_id": id}
	result, err := r.Collection.DeleteOne(context.TODO(), filter)
	if err != nil || result.DeletedCount == 0 {
		return false, err
	}
	return true, nil
}

// 🔴 NoSQL Injection 
func (r DefaultUserRepository) FindOne(ctx context.Context, filter bson.M) (*models.User, error) {
	var user models.User
	err := r.Collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}



func NewUserRepositoryDB(dbClient *mongo.Collection) *UserRepositoryDB {

	return &UserRepositoryDB{dbClient}
}
