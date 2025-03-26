type Peer struct {
    ID       string
    Address  string
    Port     int
    Files    []string
}

func NewPeer(id, address string, port int) *Peer {
    return &Peer{
        ID:      id,
        Address: address,
        Port:    port,
        Files:   []string{},
    }
}

func (p *Peer) AddFile(file string) {
    p.Files = append(p.Files, file)
}

func (p *Peer) RemoveFile(file string) {
    for i, f := range p.Files {
        if f == file {
            p.Files = append(p.Files[:i], p.Files[i+1:]...)
            break
        }
    }
}

func (p *Peer) ListFiles() []string {
    return p.Files
}