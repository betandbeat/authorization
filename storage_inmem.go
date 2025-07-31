package authorization

import (
	"sync"

	"github.com/bmatcuk/doublestar/v4"
)

type inMemoryStorage struct {
	mu         sync.RWMutex
	statements map[string]Statement
}

func NewInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{
		statements: make(map[string]Statement),
	}
}

func (s *inMemoryStorage) SaveStatement(statement Statement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statements[statement.ID] = statement
	return nil
}

func (s *inMemoryStorage) DeleteStatement(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.statements, id)
	return nil
}

func (s *inMemoryStorage) GetStatement(id string) (*Statement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stmt, ok := s.statements[id]
	if !ok {
		return nil, nil
	}
	return &stmt, nil
}

func (s *inMemoryStorage) ListStatementsByPrincipal(principal Principal) ([]Statement, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Statement
	for _, stmt := range s.statements {
		for _, p := range stmt.Principals {
			matched, err := doublestar.Match(string(p), string(principal))
			if err != nil {
				return nil, err
			}
			if matched {
				result = append(result, stmt)
				break
			}
		}
	}
	return result, nil
}
