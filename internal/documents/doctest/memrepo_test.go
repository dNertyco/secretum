package doctest

import (
	"testing"

	"github.com/dNertyco/secretum/internal/auth"
	"github.com/dNertyco/secretum/internal/auth/authtest"
	"github.com/dNertyco/secretum/internal/documents"
)

func TestMemRepoContract(t *testing.T) {
	RunRepositoryContract(t, func(*testing.T) (documents.Repository, auth.UserRepository) {
		users := authtest.NewMemUsers()
		return NewMemRepo(users), users
	})
}
