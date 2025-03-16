package services

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"newProject/dto"
	"newProject/models"
	"newProject/repository"
)

// burada once interface olusturuyoruz repo mantıgını dusun

type DefaultOrderService struct {
	Repo repository.OrderRepository
}

// burası productRepository deki interface i kullanabilelim diye yazdık
type OrderService interface {
	OrderInsert(order models.Order) (*dto.OrderDTO, error)
	OrderGetAll() ([]models.Order, error)
	OrderDelete(id primitive.ObjectID) (bool, error)
}

func (p DefaultOrderService) OrderInsert(order models.Order) (*dto.OrderDTO, error) {

	var res dto.OrderDTO
	// api dan product gelicek ya
	if len(order.Name) <= 2 {
		res.Status = false
		return &res, nil
	}

	// Sadece hata döndüren Insert metodunu çağırıyoruz.
	result, err := p.Repo.Insert(order)

	if err != nil || result == false {
		return &res, err
	}

	// İşlem başarılı olduysa, durumu true olarak ayarlıyoruz.
	res = dto.OrderDTO{Status: result}
	return &res, nil
}

func (p DefaultOrderService) OrderGetAll() ([]models.Order, error) {
	result, err := p.Repo.GetAll()

	// hata varsa handlerda bu hatayı basıcam o yuzden
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p DefaultOrderService) OrderDelete(id primitive.ObjectID) (bool, error) {

	result, err := p.Repo.Delete(id)

	if err != nil || result == false {
		return false, err
	}
	return true, nil
}

func NewOrderService(repo repository.OrderRepository) DefaultOrderService {
	return DefaultOrderService{Repo: repo}
}
