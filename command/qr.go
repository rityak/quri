package command

import (
	"errors"
	"os"

	qrcode "github.com/skip2/go-qrcode"
)

const qrImageSize = 512

func writeQR(link, path string) error {
	png, err := qrcode.Encode(link, qrcode.Medium, qrImageSize)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) //nolint:gosec // The operator selects the private output path; O_EXCL prevents overwrite and symlink following.
	if err != nil {
		return err
	}
	_, err = file.Write(png)
	return errors.Join(err, file.Close())
}
