package v2

import (
	"net/http"

	codegen "github.com/KaySar12/NextZen-UserService/codegen/user_service"
	"github.com/KaySar12/NextZen-UserService/service"
	"github.com/labstack/echo/v4"
)

func (s *UserService) DeleteEvent(ctx echo.Context, params codegen.EventUuid) error {
	m := service.MyService.Event().GetEventByUUID(params.String())
	service.MyService.Event().DeleteEvent(params.String())
	return ctx.JSON(http.StatusOK, m)
}

func (s *UserService) GetEvents(ctx echo.Context, params codegen.GetEventsParams) error {
	list := service.MyService.Event().GetEvents()
	return ctx.JSON(http.StatusOK, list)
}

func (s *UserService) DeleteEventBySerial(ctx echo.Context, serial codegen.Serial) error {
	service.MyService.Event().DeleteEventBySerial(serial)
	return ctx.JSON(http.StatusOK, serial)
}
