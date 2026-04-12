// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'lib.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$ConnectionState {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(String field0) error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(String field0)? error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(String field0)? error,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $ConnectionStateCopyWith<$Res> {
  factory $ConnectionStateCopyWith(
          ConnectionState value, $Res Function(ConnectionState) then) =
      _$ConnectionStateCopyWithImpl<$Res, ConnectionState>;
}

/// @nodoc
class _$ConnectionStateCopyWithImpl<$Res, $Val extends ConnectionState>
    implements $ConnectionStateCopyWith<$Res> {
  _$ConnectionStateCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$ConnectionState_ConnectedImplCopyWith<$Res> {
  factory _$$ConnectionState_ConnectedImplCopyWith(
          _$ConnectionState_ConnectedImpl value,
          $Res Function(_$ConnectionState_ConnectedImpl) then) =
      __$$ConnectionState_ConnectedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConnectionState_ConnectedImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res, _$ConnectionState_ConnectedImpl>
    implements _$$ConnectionState_ConnectedImplCopyWith<$Res> {
  __$$ConnectionState_ConnectedImplCopyWithImpl(
      _$ConnectionState_ConnectedImpl _value,
      $Res Function(_$ConnectionState_ConnectedImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConnectionState_ConnectedImpl extends ConnectionState_Connected {
  const _$ConnectionState_ConnectedImpl() : super._();

  @override
  String toString() {
    return 'ConnectionState.connected()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_ConnectedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(String field0) error,
  }) {
    return connected();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(String field0)? error,
  }) {
    return connected?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(String field0)? error,
    required TResult orElse(),
  }) {
    if (connected != null) {
      return connected();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return connected(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return connected?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (connected != null) {
      return connected(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Connected extends ConnectionState {
  const factory ConnectionState_Connected() = _$ConnectionState_ConnectedImpl;
  const ConnectionState_Connected._() : super._();
}

/// @nodoc
abstract class _$$ConnectionState_DisconnectedImplCopyWith<$Res> {
  factory _$$ConnectionState_DisconnectedImplCopyWith(
          _$ConnectionState_DisconnectedImpl value,
          $Res Function(_$ConnectionState_DisconnectedImpl) then) =
      __$$ConnectionState_DisconnectedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConnectionState_DisconnectedImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res,
        _$ConnectionState_DisconnectedImpl>
    implements _$$ConnectionState_DisconnectedImplCopyWith<$Res> {
  __$$ConnectionState_DisconnectedImplCopyWithImpl(
      _$ConnectionState_DisconnectedImpl _value,
      $Res Function(_$ConnectionState_DisconnectedImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConnectionState_DisconnectedImpl extends ConnectionState_Disconnected {
  const _$ConnectionState_DisconnectedImpl() : super._();

  @override
  String toString() {
    return 'ConnectionState.disconnected()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_DisconnectedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(String field0) error,
  }) {
    return disconnected();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(String field0)? error,
  }) {
    return disconnected?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(String field0)? error,
    required TResult orElse(),
  }) {
    if (disconnected != null) {
      return disconnected();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return disconnected(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return disconnected?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (disconnected != null) {
      return disconnected(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Disconnected extends ConnectionState {
  const factory ConnectionState_Disconnected() =
      _$ConnectionState_DisconnectedImpl;
  const ConnectionState_Disconnected._() : super._();
}

/// @nodoc
abstract class _$$ConnectionState_ConnectingImplCopyWith<$Res> {
  factory _$$ConnectionState_ConnectingImplCopyWith(
          _$ConnectionState_ConnectingImpl value,
          $Res Function(_$ConnectionState_ConnectingImpl) then) =
      __$$ConnectionState_ConnectingImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConnectionState_ConnectingImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res,
        _$ConnectionState_ConnectingImpl>
    implements _$$ConnectionState_ConnectingImplCopyWith<$Res> {
  __$$ConnectionState_ConnectingImplCopyWithImpl(
      _$ConnectionState_ConnectingImpl _value,
      $Res Function(_$ConnectionState_ConnectingImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConnectionState_ConnectingImpl extends ConnectionState_Connecting {
  const _$ConnectionState_ConnectingImpl() : super._();

  @override
  String toString() {
    return 'ConnectionState.connecting()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_ConnectingImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(String field0) error,
  }) {
    return connecting();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(String field0)? error,
  }) {
    return connecting?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(String field0)? error,
    required TResult orElse(),
  }) {
    if (connecting != null) {
      return connecting();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return connecting(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return connecting?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (connecting != null) {
      return connecting(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Connecting extends ConnectionState {
  const factory ConnectionState_Connecting() = _$ConnectionState_ConnectingImpl;
  const ConnectionState_Connecting._() : super._();
}

/// @nodoc
abstract class _$$ConnectionState_ErrorImplCopyWith<$Res> {
  factory _$$ConnectionState_ErrorImplCopyWith(
          _$ConnectionState_ErrorImpl value,
          $Res Function(_$ConnectionState_ErrorImpl) then) =
      __$$ConnectionState_ErrorImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String field0});
}

/// @nodoc
class __$$ConnectionState_ErrorImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res, _$ConnectionState_ErrorImpl>
    implements _$$ConnectionState_ErrorImplCopyWith<$Res> {
  __$$ConnectionState_ErrorImplCopyWithImpl(_$ConnectionState_ErrorImpl _value,
      $Res Function(_$ConnectionState_ErrorImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$ConnectionState_ErrorImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as String,
    ));
  }
}

/// @nodoc

class _$ConnectionState_ErrorImpl extends ConnectionState_Error {
  const _$ConnectionState_ErrorImpl(this.field0) : super._();

  @override
  final String field0;

  @override
  String toString() {
    return 'ConnectionState.error(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_ErrorImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$ConnectionState_ErrorImplCopyWith<_$ConnectionState_ErrorImpl>
      get copyWith => __$$ConnectionState_ErrorImplCopyWithImpl<
          _$ConnectionState_ErrorImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(String field0) error,
  }) {
    return error(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(String field0)? error,
  }) {
    return error?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(String field0)? error,
    required TResult orElse(),
  }) {
    if (error != null) {
      return error(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return error(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return error?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (error != null) {
      return error(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Error extends ConnectionState {
  const factory ConnectionState_Error(final String field0) =
      _$ConnectionState_ErrorImpl;
  const ConnectionState_Error._() : super._();

  String get field0;

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$ConnectionState_ErrorImplCopyWith<_$ConnectionState_ErrorImpl>
      get copyWith => throw _privateConstructorUsedError;
}
