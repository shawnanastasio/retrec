#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapped_file.h"

using namespace retrec;

mapped_file::~mapped_file() {
    if (valid)
        munmap(data_region, data_length);
}

status_code mapped_file::map() {
    int flags = O_CLOEXEC | (readonly ? O_RDONLY : O_RDWR);
    int fd = open(path.c_str(), flags);
    if (fd < 0)
        return status_code::BADFILE;

    struct stat statbuf;
    if (fstat(fd, &statbuf) < 0) {
        close(fd);
        return status_code::BADFILE;
    }
    data_length = statbuf.st_size;
    int prot = PROT_READ | (readonly ? 0 : PROT_WRITE);

    data_region = mmap(nullptr, data_length, prot, MAP_SHARED, fd, 0);
    if (data_region == (void *)-1) {
        close(fd);
        return status_code::BADFILE;
    }

    valid = true;
    return status_code::SUCCESS;
}