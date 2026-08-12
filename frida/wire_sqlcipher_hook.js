'use strict';

function bytesToHex(bytes) {
  if (bytes === null || bytes === undefined) {
    return null;
  }

  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    out.push(('0' + (bytes[i] & 0xff).toString(16)).slice(-2));
  }
  return out.join('');
}

function bytesPreview(bytes, limit) {
  if (bytes === null || bytes === undefined) {
    return null;
  }

  const end = Math.min(bytes.length, limit);
  let out = '';
  for (let i = 0; i < end; i++) {
    const value = bytes[i] & 0xff;
    out += value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.';
  }
  return out;
}

function emit(event, fields) {
  const payload = Object.assign({ event: event }, fields);
  send(payload);
}

function shortBacktrace() {
  try {
    return Java.backtrace({ limit: 8 }).frames
      .map(function (frame) {
        return frame.className + '.' + frame.methodName;
      })
      .join(' <- ');
  } catch (err) {
    return String(err);
  }
}

function reportKey(where, database, password) {
  emit('sqlcipher-key', {
    where: where,
    database: database === null || database === undefined ? null : String(database),
    key_len: password === null || password === undefined ? 0 : password.length,
    key_hex: bytesToHex(password),
    key_preview: bytesPreview(password, 32),
    caller: shortBacktrace()
  });
}

Java.perform(function () {
  emit('loaded', {
    package: String(Java.use('android.app.ActivityThread').currentPackageName()),
    note: 'Wire SQLCipher hooks installed'
  });

  try {
    const System = Java.use('java.lang.System');
    const loadLibrary = System.loadLibrary.overload('java.lang.String');
    loadLibrary.implementation = function (name) {
      if (String(name).indexOf('sqlcipher') !== -1) {
        emit('load-library', { name: String(name) });
      }
      return loadLibrary.call(this, name);
    };
  } catch (err) {
    emit('hook-error', { target: 'java.lang.System.loadLibrary', error: String(err) });
  }

  try {
    const SQLiteOpenHelper = Java.use('net.zetetic.database.sqlcipher.SQLiteOpenHelper');
    const cursorFactory = 'net.zetetic.database.sqlcipher.SQLiteDatabase$CursorFactory';
    const errorHandler = 'net.zetetic.database.DatabaseErrorHandler';
    const databaseHook = 'net.zetetic.database.sqlcipher.SQLiteDatabaseHook';

    const initBytes = SQLiteOpenHelper.$init.overload(
      'android.content.Context',
      'java.lang.String',
      '[B',
      cursorFactory,
      'int',
      'int',
      errorHandler,
      databaseHook,
      'boolean'
    );
    initBytes.implementation = function (
      context,
      name,
      password,
      factory,
      version,
      minimumSupportedVersion,
      handler,
      hook,
      enableWal
    ) {
      reportKey('SQLiteOpenHelper.<init>(byte[])', name, password);
      return initBytes.call(
        this,
        context,
        name,
        password,
        factory,
        version,
        minimumSupportedVersion,
        handler,
        hook,
        enableWal
      );
    };

    const initString = SQLiteOpenHelper.$init.overload(
      'android.content.Context',
      'java.lang.String',
      'java.lang.String',
      cursorFactory,
      'int',
      'int',
      errorHandler,
      databaseHook,
      'boolean'
    );
    initString.implementation = function (
      context,
      name,
      password,
      factory,
      version,
      minimumSupportedVersion,
      handler,
      hook,
      enableWal
    ) {
      emit('sqlcipher-key', {
        where: 'SQLiteOpenHelper.<init>(String)',
        database: name === null || name === undefined ? null : String(name),
        key_len: password === null || password === undefined ? 0 : String(password).length,
        key_string: password === null || password === undefined ? null : String(password),
        caller: shortBacktrace()
      });
      return initString.call(
        this,
        context,
        name,
        password,
        factory,
        version,
        minimumSupportedVersion,
        handler,
        hook,
        enableWal
      );
    };
  } catch (err) {
    emit('hook-error', {
      target: 'net.zetetic.database.sqlcipher.SQLiteOpenHelper',
      error: String(err)
    });
  }

  try {
    const SQLiteDatabase = Java.use('net.zetetic.database.sqlcipher.SQLiteDatabase');
    const cursorFactory = 'net.zetetic.database.sqlcipher.SQLiteDatabase$CursorFactory';
    const errorHandler = 'net.zetetic.database.DatabaseErrorHandler';
    const databaseHook = 'net.zetetic.database.sqlcipher.SQLiteDatabaseHook';

    const openBytes = SQLiteDatabase.openDatabase.overload(
      'java.lang.String',
      '[B',
      cursorFactory,
      'int',
      errorHandler,
      databaseHook
    );
    openBytes.implementation = function (path, password, factory, flags, handler, hook) {
      reportKey('SQLiteDatabase.openDatabase(byte[])', path, password);
      return openBytes.call(this, path, password, factory, flags, handler, hook);
    };

    const openString = SQLiteDatabase.openDatabase.overload(
      'java.lang.String',
      'java.lang.String',
      cursorFactory,
      'int',
      errorHandler,
      databaseHook
    );
    openString.implementation = function (path, password, factory, flags, handler, hook) {
      emit('sqlcipher-key', {
        where: 'SQLiteDatabase.openDatabase(String)',
        database: path === null || path === undefined ? null : String(path),
        key_len: password === null || password === undefined ? 0 : String(password).length,
        key_string: password === null || password === undefined ? null : String(password),
        caller: shortBacktrace()
      });
      return openString.call(this, path, password, factory, flags, handler, hook);
    };
  } catch (err) {
    emit('hook-error', {
      target: 'net.zetetic.database.sqlcipher.SQLiteDatabase',
      error: String(err)
    });
  }
});
