all: clean encfile
.PHONY: all

unexport GOFLAGS

GOCC?=go

systemstr = $(shell lsb_release -i|cut -f 2).$(shell lsb_release -r|cut -f 2)
ldflags=-X=encfile/version.GITCOMMIT=+git.$(subst -,.,$(shell git describe --always --match=NeVeRmAtCh --dirty 2>/dev/null || git rev-parse --short HEAD 2>/dev/null)).$(systemstr)

ifneq ($(strip $(LDFLAGS)),)
        ldflags+=-extldflags=$(LDFLAGS)
endif
GOFLAGS+=-ldflags="$(ldflags)"

encfile:
	$(GOCC) build $(GOFLAGS) -o encfile .

clean:
	rm -rf encfile
