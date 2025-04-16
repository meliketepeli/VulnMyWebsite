package app

import (
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"net/http"
	"myWebsite-main/models"
	"myWebsite-main/services"
)

type ProductHandler struct {
	Service services.ProductService
}

func (h ProductHandler) CreateProduct(c *fiber.Ctx) error {

	var product models.Product
	// json gelen veriyi struct turune donusturme yapıyoruz
	if err := c.BodyParser(&product); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err.Error())
	}

	result, err := h.Service.ProductInsert(product)

	if err != nil || result.Status == false {
		return err
	}

	return c.Status(http.StatusCreated).JSON(result)
}

// service verilerini handlerdan alıyor
func (h ProductHandler) GetAllProduct(c *fiber.Ctx) error {

	result, err := h.Service.ProductGetAll()

	if err != nil {
		log.Println("Ürünler alınırken hata oluştu:", err)
		return c.Status(http.StatusInternalServerError).JSON(err.Error())
	}

	return c.Status(http.StatusOK).JSON(result)

	// Ürünleri HTML şablonuna aktar
	return c.Render("products.html", fiber.Map{
		"Products": result,
	})

}

func (h ProductHandler) DeleteProduct(c *fiber.Ctx) error {

	// id buradan string geliyor
	query := c.Params("id")
	// string id yi hex e donusturme
	cnv, _ := primitive.ObjectIDFromHex(query)

	result, err := h.Service.ProductDelete(cnv)

	if err != nil || result == false {

		//kendi modelimizi oluşturmak gibi düşünebiliriz (buna bak bence)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"State": false})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"State": true})
}