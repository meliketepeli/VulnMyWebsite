package routes

import (
	"github.com/gofiber/fiber/v2"
	"newProject/app" // Burada app paketini import etmelisin
)

func SetupRoutes(app *fiber.App, pr app.ProductHandler, us app.UserHandler, ca app.CartHandler, or app.OrderHandler) {

	app.Get("/api/products", pr.GetAllProduct)
	app.Post("/api/product", pr.CreateProduct)
	app.Delete("/api/products/:id", pr.DeleteProduct)

	app.Get("/api/users", us.GetAllUser)
	app.Post("/api/user", us.CreateUser)
	app.Delete("/api/users/:id", us.DeleteUser)

	app.Get("/api/carts", ca.GetAllCart)
	app.Post("/api/cart", ca.CreateCart)
	app.Delete("/api/carts/:id", ca.DeleteCart)

	app.Get("/api/orders", or.GetAllOrder)
	app.Post("/api/order", or.CreateOrder)
	app.Delete("/api/orders/:id", or.DeleteOrder)

}
