package types

import "gorm.io/gorm"

type RefreshToken struct {
	gorm.Model

	Token  string
	NodeID NodeID
}
