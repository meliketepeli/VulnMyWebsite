package services

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"newProject/dto"
	"newProject/models"
	"newProject/repository"
)

// burada once interface olusturuyoruz repo mantıgını dusun

type DefaultProductService struct {
	Repo repository.ProductRepository
}

// burası productRepository deki interface i kullanabilelim diye yazdık
type ProductService interface {
	ProductInsert(product models.Product) (*dto.ProductDTO, error)
	ProductGetAll() ([]models.Product, error)
	ProductDelete(id primitive.ObjectID) (bool, error)
}

func (p DefaultProductService) ProductInsert(product models.Product) (*dto.ProductDTO, error) {

	var res dto.ProductDTO
	// api dan product gelicek ya
	if len(product.Name) <= 2 {
		res.Status = false
		return &res, nil
	}

	// Sadece hata döndüren Insert metodunu çağırıyoruz.
	result, err := p.Repo.Insert(product)

	if err != nil || result == false {
		return &res, err
	}

	// İşlem başarılı olduysa, durumu true olarak ayarlıyoruz.
	res = dto.ProductDTO{Status: result}
	return &res, nil
}

func (p DefaultProductService) ProductGetAll() ([]models.Product, error) {
	result, err := p.Repo.GetAll()

	// hata varsa handlerda bu hatayı basıcam o yuzden
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p DefaultProductService) ProductDelete(id primitive.ObjectID) (bool, error) {

	result, err := p.Repo.Delete(id)

	if err != nil || result == false {
		return false, err
	}
	return true, nil
}

func NewProductService(repo repository.ProductRepository) DefaultProductService {
	return DefaultProductService{Repo: repo}
}
