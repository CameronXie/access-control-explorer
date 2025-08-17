package trie

import (
	"fmt"
)

const (
	WildcardSegment = "*"
)

// Node represents a trie node with generic value type T
type Node[T any] struct {
	Children map[string]*Node[T]
	Value    T
	IsEnd    bool
}

// New creates and returns a new instance of Node with an initialized Children map.
func New[T any]() *Node[T] {
	return &Node[T]{
		Children: make(map[string]*Node[T]),
	}
}

// Insert adds a value to the trie at the specified paths, creating intermediate nodes if not present.
// Returns an error if paths are empty or the paths already exist in the trie.
func (n *Node[T]) Insert(paths []string, value T) error {
	currentNode := n

	// Traverse/create paths in trie
	for _, p := range paths {
		if currentNode.Children[p] == nil {
			currentNode.Children[p] = &Node[T]{
				Children: make(map[string]*Node[T]),
			}
		}

		currentNode = currentNode.Children[p]
	}

	// Check for duplicate paths
	if currentNode.IsEnd {
		return fmt.Errorf("paths %v already exists", paths)
	}

	// Mark as end node and store value
	currentNode.Value = value
	currentNode.IsEnd = true
	return nil
}

// Search finds a node by paths, supporting wildcard matching
func (n *Node[T]) Search(path []string) (*Node[T], error) {
	currentNode := n

	// Traverse paths with wildcard fallback
	for _, p := range path {
		// Try exact match first
		if currentNode.Children[p] != nil {
			currentNode = currentNode.Children[p]
			continue
		}

		// Fall back to wildcard match
		if currentNode.Children[WildcardSegment] != nil {
			currentNode = currentNode.Children[WildcardSegment]
			continue
		}

		return nil, fmt.Errorf("no route found for key %s in paths %v", p, path)
	}

	// Verify complete paths exists
	if !currentNode.IsEnd {
		return nil, fmt.Errorf("paths %v not found", path)
	}

	return currentNode, nil
}
