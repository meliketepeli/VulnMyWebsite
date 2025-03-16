package services

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"myWebsite-main/dto"
	"myWebsite-main/models"
	"myWebsite-main/repository"
)

// burada once interface olusturuyoruz repo mantıgını dusun

type DefaultUserService struct {
	Repo repository.UserRepository
}

// burası UserRepository deki interface i kullanabilelim diye yazdık 
type UserService interface {
	UserInsert(user models.User) (*dto.UserDTO, error)
	UserGetAll() ([]models.User, error)
	UserDelete(id primitive.ObjectID) (bool, error)	
	UserLogin(username string, password string) (*models.User, error) // 🔴 NoSQL Injection'a açık giriş fonksiyonu eklendi

}

func (u DefaultUserService) UserInsert(user models.User) (*dto.UserDTO, error) {

	var res dto.UserDTO
	// api dan user  gelicek ya
	if len(user.Username) <= 2 {
		res.Status = false
		return &res, nil
	}

	// Sadece hata döndüren Insert metodunu çağırıyoruz.
	result, err := u.Repo.Insert(user)

	if err != nil || result == false {
		return &res, err
	}

	// İşlem başarılı olduysa, durumu true olarak ayarlıyoruz.
	res = dto.UserDTO{Status: result}
	return &res, nil
}

func (u DefaultUserService) UserGetAll() ([]models.User, error) {
	result, err := u.Repo.GetAll()

	// hata varsa handlerda bu hatayı basıcam o yuzden
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (u DefaultUserService) UserDelete(id primitive.ObjectID) (bool, error) {

	result, err := u.Repo.Delete(id)

	if err != nil || result == false {
		return false, err
	}
	return true, nil
}

//nosql ınjectıon
func (u DefaultUserService) UserLogin(username interface{}, password interface{}) (*models.User, error) {
    // Kullanıcı girdisini olduğu gibi MongoDB sorgusuna aktarma
    filter := bson.M{"username": username, "password": password}

    result, err := u.Repo.FindOne(context.TODO(), filter)
    if err != nil {
        return nil, err
    }
    return result, nil
}



func NewUserService(repo repository.UserRepository) DefaultUserService {
	return DefaultUserService{Repo: repo}
}