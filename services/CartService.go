package services

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"newProject/dto"
	"newProject/models"
	"newProject/repository"
)

// burada once interface olusturuyoruz repo mantıgını dusun

type DefaultCartService struct {
	Repo repository.CartRepository
}

// burası productRepository deki interface i kullanabilelim diye yazdık
type CartService interface {
	CartInsert(cart models.Cart) (*dto.CartDTO, error)
	CartGetAll() ([]models.Cart, error)
	CartDelete(id primitive.ObjectID) (bool, error)
}

func (p DefaultCartService) CartInsert(cart models.Cart) (*dto.CartDTO, error) {

	var res dto.CartDTO
	// api dan product gelicek ya
	if len(cart.Name) <= 2 {
		res.Status = false
		return &res, nil
	}

	// Sadece hata döndüren Insert metodunu çağırıyoruz.
	result, err := p.Repo.Insert(cart)

	if err != nil || result == false {
		return &res, err
	}

	// İşlem başarılı olduysa, durumu true olarak ayarlıyoruz.
	res = dto.CartDTO{Status: result}
	return &res, nil
}

func (p DefaultCartService) CartGetAll() ([]models.Cart, error) {
	result, err := p.Repo.GetAll()

	// hata varsa handlerda bu hatayı basıcam o yuzden
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p DefaultCartService) CartDelete(id primitive.ObjectID) (bool, error) {

	result, err := p.Repo.Delete(id)

	if err != nil || result == false {
		return false, err
	}
	return true, nil
}

func NewCartService(repo repository.CartRepository) DefaultCartService {
	return DefaultCartService{Repo: repo}
}
