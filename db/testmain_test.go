package db

import (
	"github.com/bcyw/artex/internal/testdb"
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(testdb.Run(m)) }
