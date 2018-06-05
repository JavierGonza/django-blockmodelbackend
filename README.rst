=============================
django-blockmodelbackend
=============================

Custom model backend for blocking users and ip after several attempts to access wrongly


Installation
------------

#. Install django-blockmodelbackend::

    pip install django-blockmodelbackend


#. Add ``blockmodelbackend`` to your ``INSTALLED_APPS`` settings::

	INSTALLED_APPS = [
		...
		'blockmodelbackend',
	]

#. Run the ``makemigrations`` and ``migrate`` commands::

	python manage.py makemigrations blockmodelbackend 
	python manage.py migrate

#. Add the new backend class to your ``AUTHENTICATION_BACKENDS`` settings::

	AUTHENTICATION_BACKENDS = [
		...
		'blockmodelbackend.modelbackend.BlockModelBackend',
	]

Configuration
-------------

There is some parameters to customize the backend.

. ``MAX_ACCESS_ATTEMPTS``:[ ``3`` ] maximum numbers of wrong authentication attempts before blocking

. ``LOCK_DURATION``:[ ``5`` ] lock duration in minutes

. ``DELTA_LOCK_DURATION``:[ ``1`` ] increase in the lock duration in minutes

. ``USER_PERMANENT_BLOCK``:[ ``False`` ] boolean value

. ``IP_PERMANENT_BLOCK``:[ ``False`` ] boolean value

. ``BLOCK_TYPE``:[ ``both`` ] choice between ``both``, ``user`` or ``ip``
