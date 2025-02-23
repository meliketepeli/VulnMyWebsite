package services

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"newProject/dto"
	"newProject/models"
	"newProject/repository"
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

func NewUserService(repo repository.UserRepository) DefaultUserService {
	return DefaultUserService{Repo: repo}
}
