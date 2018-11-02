//Copyright 2014 sndnvaps
//
package selinux

import (
	"os"
	"testing"
)

func TestSelinux_enabled(t *testing.T) {
	if Enabled() {
		t.Log("SELinux status = Enabled")
	} else {
		t.Log("SELinux status = Disabled")
	}
}

func TestGetfilecon(t *testing.T) {
	var flabel string
	var size int
	flabel, size = Lgetfilecon("selinux.go")
	if size > 0 {
		t.Logf("selinux.go label = %s", flabel)
	} else {
		t.Errorf("Unable to get label")
	}
}

func TestSetfilecon(t *testing.T) {
	path := "selinux.go"
	scon := "system_u:object_r:usr_t:s0"
	rc, _ := Lsetfilecon(path, scon)
	if rc != 0 {
		t.Error("Setfilecon failed")
	} else {
		t.Log("Setfilecon success")
	}
}

// fd := f.Fd()
// os.Fileinfo
func TestFsetfilecon(t *testing.T) {
	f, err := os.Create("test.selinux")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	fd := int(f.Fd())

	scon := "system_u:object_r:usr_t:s0"
	rc := Fsetfilecon(fd, scon)
	if rc != nil {
		t.Errorf("fsetfilecon failed: %s", err.Error())
	} else {
		t.Logf("fsetfilecon: test.selinux -> %s", scon)
	}
}

func TestMatchpathcon(t *testing.T) {
	path := "selinux_test.go"
	mode, ecode := GetModeT(path)
	if ecode == 0 {
		_, err := Matchpathcon(path, mode)
		if err != nil {
			t.Errorf("selinux_test.go selabel = %s", err.Error())
		}
	}
}

func TestSelinux_getenforcemode(t *testing.T) {
	var enforce int
	enforce = Getenforcemode()
	t.Logf("%s", "Selinux mode = ")
	if enforce == Enforcing {
		t.Logf("Enforcing mode")
	} else if enforce == Permissive {
		t.Logf("permissive mode")
	} else if enforce == Disabled {
		t.Logf("Disabled mode")
	} else {
		t.Errorf("Unknown mode %d", enforce)
	}
}
func TestGetPidcon(t *testing.T) {
	pid := os.Getpid()
	t.Logf("PID:%d MCS:%s\n", pid, IntToMcs(pid, 1023))
	if scon, err := Getpidcon(pid); err == nil {
		t.Logf("pid = %d, security_context = %s ", pid, scon)
	} else {
		t.Errorf("Unable to GetPidcon: %s", err.Error())
	}
}

func TestLgetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		t.Error(err)
	}
	fcXattr, err := Lgetxattr(fc.Name(), SecuritySelinux)
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("se_xattrs_test.txt xattr = %s", string(fcXattr))
	}

}

func TestLsetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		t.Error(err)
	}
	scon := "system_u:object_r:usr_t:s0"
	err = Lsetxattr(fc.Name(), SecuritySelinux, []byte(scon), 0)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("set ", fc.Name(), "selinux_label -> ", scon, "success")
	}

}

func TestFgetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test_fd.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		t.Error(err)
	}
	fcXattr, err := Fgetxattr(fc.Fd(), SecuritySelinux)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("TestFgetxattr:se_xattrs_test.txt xattr = ", string(fcXattr))
	}

}

func TestFsetxattr(t *testing.T) {
	fc, err := os.OpenFile("se_xtars_test_fd.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0755)
	defer fc.Close()
	if err != nil {
		t.Error(err)
	}

	scon := "system_u:object_r:usr_t:s0"

	err = Fsetxattr(fc.Fd(), SecuritySelinux, []byte(scon), 0)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("TestFsetxattr:se_xattrs_test_fd.txt xattr = ", scon)
	}

}
