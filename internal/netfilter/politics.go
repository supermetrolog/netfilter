package netfilter

type AcceptPoliticHandler struct {
}

func (p *AcceptPoliticHandler) Handle(c Context) (bool, error) {
	return true, nil
}

type DropPoliticHandler struct {
}

func (p *DropPoliticHandler) Handle(c Context) (bool, error) {
	return false, nil
}

type RejectPoliticHandler struct {
}

func (p *RejectPoliticHandler) Handle(c Context) (bool, error) {
	return false, nil
}
