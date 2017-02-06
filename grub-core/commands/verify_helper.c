#include <grub/file.h>
#include <grub/verify.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

struct grub_file_verifier *grub_file_verifiers;

struct grub_verified
{
  grub_file_t file;
  void *buf;
};
typedef struct grub_verified *grub_verified_t;

static void
verified_free (grub_verified_t verified)
{
  if (verified)
    {
      grub_free (verified->buf);
      grub_free (verified);
    }
}

static grub_ssize_t
verified_read (struct grub_file *file, char *buf, grub_size_t len)
{
  grub_verified_t verified = file->data;

  grub_memcpy (buf, (char *) verified->buf + file->offset, len);
  return len;
}

static grub_err_t
verified_close (struct grub_file *file)
{
  grub_verified_t verified = file->data;

  grub_file_close (verified->file);
  verified_free (verified);
  file->data = 0;

  /* device and name are freed by parent */
  file->device = 0;
  file->name = 0;

  return grub_errno;
}

struct grub_fs verified_fs =
{
  .name = "verified_read",
  .read = verified_read,
  .close = verified_close
};

static grub_file_t
grub_verify_helper_open (grub_file_t io, enum grub_file_type type)
{
  grub_verified_t verified = 0;
  struct grub_file_verifier *ver;
  void *context;
  grub_file_t ret = 0;
  grub_err_t err;

  if ((type & GRUB_FILE_TYPE_MASK) == GRUB_FILE_TYPE_SIGNATURE
      || (type & GRUB_FILE_TYPE_MASK) == GRUB_FILE_TYPE_VERIFY_SIGNATURE
      || (type & GRUB_FILE_TYPE_SKIP_SIGNATURE))
    return io;

  if (io->device->disk && 
      (io->device->disk->dev->id == GRUB_DISK_DEVICE_MEMDISK_ID
       || io->device->disk->dev->id == GRUB_DISK_DEVICE_PROCFS_ID))
    return io;

  FOR_LIST_ELEMENTS(ver, grub_file_verifiers)
    {
      enum grub_verify_flags flags = 0;
      err = ver->init (io, type, &context, &flags);
      if (err)
	goto fail_noclose;
      if (!(flags & GRUB_VERIFY_FLAGS_SKIP_VERIFICATION))
	break;
    }
  if (!ver)
    /* No verifiers wanted to verify. Just return underlying file.  */
    return io;

  ret = grub_malloc (sizeof (*ret));
  if (!ret)
    {
      goto fail;
    }
  *ret = *io;

  ret->fs = &verified_fs;
  ret->not_easily_seekable = 0;
  if (ret->size >> (sizeof (grub_size_t) * GRUB_CHAR_BIT - 1))
    {
      grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		  "big file signature isn't implemented yet");
      goto fail;
    }
  verified = grub_malloc (sizeof (*verified));
  if (!verified)
    {
      goto fail;
    }
  verified->buf = grub_malloc (ret->size);
  if (!verified->buf)
    {
      goto fail;
    }
  if (grub_file_read (io, verified->buf, ret->size) != (grub_ssize_t) ret->size)
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
		    io->name);
      goto fail;
    }
  
  err = ver->write (context, verified->buf, ret->size);
  if (err)
    goto fail;

  err = ver->fini ? ver->fini (context) : GRUB_ERR_NONE;
  if (err)
    goto fail;

  ver->close (context);

  FOR_LIST_ELEMENTS_NEXT(ver, grub_file_verifiers)
    {
      enum grub_verify_flags flags = 0;
      err = ver->init (io, type, &context, &flags);
      if (err)
	goto fail_noclose;
      if (flags & GRUB_VERIFY_FLAGS_SKIP_VERIFICATION)
	continue;
      err = ver->write (context, verified->buf, ret->size);
      if (err)
	goto fail;

      err = ver->fini ? ver->fini (context) : GRUB_ERR_NONE;
      if (err)
	goto fail;

      ver->close (context);
    }

  verified->file = io;
  ret->data = verified;
  return ret;

 fail:
  ver->close (context);
 fail_noclose:
  verified_free (verified);
  grub_free (ret);
  return NULL;
}

GRUB_MOD_INIT(verify_helper)
{
  grub_file_filter_register (GRUB_FILE_FILTER_VERIFY, grub_verify_helper_open);
}

GRUB_MOD_FINI(verify_helper)
{
  grub_file_filter_unregister (GRUB_FILE_FILTER_VERIFY);
}
