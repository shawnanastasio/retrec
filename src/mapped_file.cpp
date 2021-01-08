/**
 * Copyright 2020-2021 Shawn Anastasio.
 *
 * This file is part of retrec.
 *
 * retrec is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * retrec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with retrec.  If not, see <https://www.gnu.org/licenses/>.
 */

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