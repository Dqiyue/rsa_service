/**
 * 
 * @filename:     base.h
 * @author:       kylin
 * @email:        kylin.du@outlook.com
 * @dateTime:     2018-06-06 Wed 15:34:58
 * @copyright:    kylin.du
 * @description:  
 * 
 */

#ifndef _BASE_H_
#define _BASE_H_

#include <stdint.h>
#include <stdlib.h>
//#include <jemalloc/jemalloc.h>
#include <assert.h>

namespace NetCore {


//test_builtin_expect.c 
#define INVALID_HANDLE -1

#ifdef JEMALLOC_NO_DEMANGLE
	#define NC_MALLOC je_malloc 
	#define NC_FREE je_free
	#define NC_CALLOC je_calloc
	#define NC_REALLOC je_realloc
	#define nc_malloc je_malloc 
	#define nc_free je_free
	#define nc_calloc je_calloc
	#define nc_realloc je_realloc
#else
	#define NC_MALLOC malloc 
	#define NC_FREE free
	#define NC_CALLOC calloc
	#define NC_REALLOC realloc
	#define nc_malloc malloc
	#define nc_free free
	#define nc_calloc calloc
	#define nc_realloc realloc
#endif

#ifndef  LIKELY
	#ifdef __GCC__
		#define LIKELY(x) __builtin_expect(!!(x), 1)
	#else
		#define LIKELY(x) (x)
	#endif
#endif

#ifndef UNLIKELY
	#ifdef __GCC__
		#define UNLIKELY(x) __builtin_expect(!!(x), 0)
	#else
		#define UNLIKELY(x) (x)
	#endif
#endif

#define MIN(a,b) ((a) > (b) ? (b) : (a))
#define MAX(a,b) ((a) > (b) ? (a) : (b))


//base func define
#define CONN(a,b) a##b
//#define TOCHAR(ch) #@ch
#define TOSTR(a) #a


#define MEMBER_POS(type,member) ((uint32_t)&(((type*)0)->(member)))
#define MEMBER_SIZE(type,member) (sizeof(((type*)0)->(member)))
#define MEMBER_ENTRY(ptr,type,member,mtype)  *((mtype*)((unsigned char*)(ptr) + (uint32_t)(&(((type*)0)->member))))

//#define NC_TRACE()

#define SWAP(a,b) { 			\
 	a ^= b;						\
	b ^= a;						\
	a ^= b;						\
}

#define SAFE_FREE(ptr) { 		\
	if (ptr) { 					\
		nc_free(ptr);  			\
		(ptr) = 0; 				\
	}							\
}


#define SAFE_DELETE(ptr) { 		\
	if (ptr) { 					\
		delete ptr;  			\
		(ptr) = 0; 				\
	}							\
}

#define SAFE_CLOSE_FP(fp) {   	\
	if (fp) { 					\
		fclose(fp);  			\
		(fp) = 0; 				\
	}							\
}

#define SAFE_CLOSE(fd) { 		\
	if (fd != INVALID_HANDLE) {	\
		close(fd);				\
		fd = INVALID_HANDLE;	\
	}							\
}

#define COMM_MALLOC_TYPE(type) ((type*)nc_malloc(sizeof(type)))
#define COMM_MALLOC_SIZE(type,size) ((type*)nc_malloc(size))
#define COMM_MALLOC_ARRY(type,num) ((type*)nc_malloc(sizeof(type) * (num))


const char WEEKDAY[][7]   = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};


typedef struct nc_data{
	nc_data():_data(0),_size(0),_capacity(0){}
	~nc_data(){SAFE_FREE(_data);}
	uint8_t* _data;
	uint32_t _size;
	uint32_t _capacity;
}data_t;

#define nc_new_data(cap,name) {\
	data_t* name = (data_t*)nc_malloc(sizeof(data_t));\
	if (name != 0) {\
		name->_data = (uint8_t*)nc_malloc(cap);\
		if (!name->_data) {\
			nc_free(name);\
			name = 0;\
		}else {\
			name->_size = 0;\
			name->_capacity = cap;\
		}\
	}\
}

#define nc_free_data(name) {\
	if (name) {\
		SAFE_FREE(name->_data);\
		nc_free(name);\
		name = 0;\
	}\
}


};

#endif //_BASE_H_