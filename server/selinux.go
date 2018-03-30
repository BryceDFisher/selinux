package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BryceDFisher/selinux"
	logging "github.com/Novetta/go.logging"
)

var (
	tmpDir string
)

//FS implements a http.FileSystem
type FS struct {
	http.Dir
}

//Open opens the requested file
func (fs FS) Open(path string) (nf http.File, err error) {
	f, oerr := fs.Dir.Open(path)
	if f != nil {
		nf = F{
			File: f.(*os.File),
		}
	}
	return nf, oerr
}

//F implements a http.File
type F struct {
	*os.File
}

//Readdir returns items in dir up to count
func (f F) Readdir(count int) (infos []os.FileInfo, err error) {
	names, rerr := f.Readdirnames(count)
	if rerr != nil {
		err = rerr
	}
	dirName := f.Name()
	if dirName == "" {
		dirName = "."
	}

	logging.Mandatory("Found %d names: %q", len(names), names)
	for _, n := range names {
		i, lerr := os.Lstat(filepath.Join(dirName, n))
		if i != nil {
			infos = append(infos, i)
			if err == nil {
				err = lerr
			}
		}
	}
	logging.Mandatory("Stat %d files", len(infos))
	return
}

func main() {

	var err error
	tmpDir, err = ioutil.TempDir("/opt/kerbproxy", "selinux")
	if err != nil {
		logging.Fatalf("Unable to create temp dir: %s", err.Error())
	}
	con := selinux.Getcon()
	dCon := selinux.NewContext(con)
	dCon.SetLevel("s0")
	selinux.Setfilecon(tmpDir, dCon.Get())

	logging.Mandatory("Created temp dir %q", tmpDir)

	permsHandler := http.NewServeMux()
	permsHandler.HandleFunc("/", PrintLabel)
	permsHandler.HandleFunc("/create/", CreateFile)
	f := FS{
		Dir: http.Dir(tmpDir),
	}
	permsHandler.Handle("/get/", http.StripPrefix("/get/", http.FileServer(f)))
	a := AuthHandler{
		h: permsHandler,
	}
	go startServe(":81", a)
	startServe(":8008", a)
}

//AuthHandler sets the context then calls the handler
type AuthHandler struct {
	h http.Handler
}

func (a AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setPerms(r)
	a.h.ServeHTTP(w, r)
}

func startServe(port string, h http.Handler) {
	err := http.ListenAndServe(port, h)
	logging.Fatalf("Error starting server: %s", err.Error())
}

//PrintLabel prints and returns the selinux context of the currently running process
func PrintLabel(w http.ResponseWriter, r *http.Request) {
	con := selinux.Getcon()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(con))
	logging.Mandatory("Current contxt: %s", con)
	con = selinux.Getcon()
	logging.Mandatory("Exiting thread: %s", con)
}

//CreateFile creates a file on the filesystem
func CreateFile(w http.ResponseWriter, r *http.Request) {
	f, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		logging.Errorf("Unable to create file: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fcon, err := selinux.Fgetxattr(f.Fd(), selinux.SecuritySelinux)
	if err != nil {
		logging.Errorf("Unable to get inital file attributes: %s", err.Error())
	}

	if strings.Contains(strings.ToLower(r.RequestURI), "lower") {
		logging.Mandatory("Lowering file perms")
		con := selinux.NewContext(string(fcon))
		con.SetLevel("s0")
		fcon = []byte(con.Get())
		err = selinux.Fsetfilecon(int(f.Fd()), string(fcon))
	}

	logging.Mandatory("New file permissions: %s", fcon)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Created %q with perms %q", f.Name(), fcon)))
	f.Close()
}

func setPerms(r *http.Request) {
	runtime.LockOSThread()
	logging.Mandatory("Request for %q on %q", r.RequestURI, r.Host)
	con := selinux.Getcon()
	c := selinux.NewContext(con)
	if strings.Contains(r.Host, "8008") {
		logging.Mandatory("Dropping perms")
		c.SetLevel("s0-s3")
		err := selinux.Setcon(c.Get())
		if err != nil {
			logging.Errorf("Unable to set con: %s", err.Error())
		}
	} else {
		c.SetLevel("s0-s5")
		err := selinux.Setcon(c.Get())
		if err != nil {
			logging.Errorf("Unable to set con: %s", err.Error())
		}
	}
	l := strings.Split(c.GetLevel(), "-")
	c.SetLevel(l[len(l)-1])
	err := selinux.Setfscreatecon(c.Get())
	if err != nil {
		logging.Errorf("Unable to set future file permissions: %s", err.Error())
	}

}
