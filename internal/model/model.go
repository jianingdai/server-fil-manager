package model

import "time"

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
}

type Root struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path,omitempty"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"createdAt"`
}

type Permissions struct {
	List      bool `json:"list"`
	Download  bool `json:"download"`
	Upload    bool `json:"upload"`
	CreateDir bool `json:"createDir"`
	Rename    bool `json:"rename"`
	Delete    bool `json:"delete"`
	Copy      bool `json:"copy"`
	Move      bool `json:"move"`
	Search    bool `json:"search"`
}

type RootGrant struct {
	Root        Root        `json:"root"`
	Permissions Permissions `json:"permissions"`
}

type TrashEntry struct {
	ID           string    `json:"id"`
	RootID       int64     `json:"rootId"`
	RootName     string    `json:"rootName"`
	OriginalPath string    `json:"originalPath"`
	Name         string    `json:"name"`
	DeletedBy    int64     `json:"deletedBy"`
	DeletedAt    time.Time `json:"deletedAt"`
}

type FileEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Size    int64  `json:"size"`
	ModTime string `json:"modTime"`
	Mode    string `json:"mode"`
}
