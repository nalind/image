package explode

import (
	"github.com/containers/image/types"
)

var (
	_img       types.Image            = &explodeImage{}
	_imgd      types.ImageDestination = &explodeImage{}
	_imgs      types.ImageSource      = &explodeImage{}
	_ref       types.ImageReference   = &explodeReference{}
	_transport types.ImageTransport   = &explodeTransport{}
)
