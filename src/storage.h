/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <fcntl.h>
#include <sys/types.h>

int create_dirs(const char *filename);

ssize_t read_file(void *buffer, size_t len, const char *path_fmt, ...)
	__attribute__((format(printf, 3, 4)));

ssize_t write_file(const void *buffer, size_t len, const char *path_fmt, ...)
	__attribute__((format(printf, 3, 4)));

char *storage_get_file_path(const char *imsi, const char *store);
GKeyFile *storage_open(const char *imsi, const char *store);
void storage_sync(const char *imsi, const char *store, GKeyFile *keyfile);
void storage_close(const char *imsi, const char *store, GKeyFile *keyfile,
			gboolean save);
