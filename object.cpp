
#include "stratum.h"

/*  annoying bug in thread handling
 	original dev didn't notice that list implementation only protects list pointers,
	not the content of the list elements.
	leads to memory leakage on heavy load and stratum gets real slow as internal lists gets too large
*/
YAAMP_OBJECT::YAAMP_OBJECT()
{
	yaamp_create_mutex(&object_mutex);

	id = 0;
	lock_count = 0;

	unlock = false;
	deleted = false;
}

YAAMP_OBJECT::~YAAMP_OBJECT()
{
	// nothing
}
YAAMP_OBJECT *object_find(CommonList *list, int id, bool lock)
{
	if(lock) list->Enter();
	for(CLI li = list->first; li; li = li->next)
	{
		YAAMP_OBJECT *object = (YAAMP_OBJECT *)li->data;
		if(object->id == id)
		{
			if(lock)
			{
				object_lock(object);
				list->Leave();
			}

			return object;
		}
	}

	if(lock) list->Leave();
	return NULL;
}

void object_lock(YAAMP_OBJECT *object)
{
	if(!object) return;
	CommonLock(&object->object_mutex);
	object->lock_count++;
	CommonUnlock(&object->object_mutex);
}

void object_unlock(YAAMP_OBJECT *object)
{
	if(!object) return;
	CommonLock(&object->object_mutex);
	object->lock_count--;
	if (object->lock_count < 0)
		debuglog("object lockcount negative!");
	CommonUnlock(&object->object_mutex);
}

void object_delete(YAAMP_OBJECT *object)
{
	if(!object) return;
	CommonLock(&object->object_mutex);
	object->deleted = true;
	CommonUnlock(&object->object_mutex);
}

void object_prune(CommonList *list, YAAMP_OBJECT_DELETE_FUNC deletefunc)
{
	list->Enter();
	for(CLI li = list->first; li && list->count > 0; )
	{
		CLI todel = li;
		YAAMP_OBJECT *object = (YAAMP_OBJECT *)li->data;
		li = li->next;

		if(!object) continue;

		if(object->deleted && !object->lock_count)
		{
			deletefunc(object);
			todel->data = NULL;
			list->Delete(todel);
		}

		else if(object->lock_count && object->unlock)
			object->lock_count--;
	}

	list->Leave();
}

void object_prune_debug(CommonList *list, YAAMP_OBJECT_DELETE_FUNC deletefunc)
{
	list->Enter();
	for(CLI li = list->first; li && list->count > 0; )
	{
		CLI todel = li;
		YAAMP_OBJECT *object = (YAAMP_OBJECT *)li->data;
		li = li->next;

		if(!object) continue;

		if(object->deleted && object->lock_count)
			debuglog("object set for delete is locked\n");

		if(object->deleted && !object->lock_count)
		{
			deletefunc(object);
			todel->data = NULL;
			list->Delete(todel);
		}

		else if(object->lock_count && object->unlock)
			object->lock_count--;
	}

	if (list->count)
		debuglog("still %d objects in list\n", list->count);

	list->Leave();
}





