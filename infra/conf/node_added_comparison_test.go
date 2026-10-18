package conf_test

import (
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TypedMessage.Value contains protobuf bytes, whose map order is unspecified.
// Compare every field after deterministic serialization of embedded messages;
// do not change the original production serializer or ignore configuration data.
func addedConfigEqual(a, b proto.Message) bool {
	x, y := proto.Clone(a), proto.Clone(b)
	return normalizeAddedMessage(x.ProtoReflect()) && normalizeAddedMessage(y.ProtoReflect()) && proto.Equal(x, y)
}

func normalizeAddedMessage(m protoreflect.Message) bool {
	if typed, ok := m.Interface().(*serial.TypedMessage); ok {
		value, err := typed.GetInstance()
		if err != nil || !normalizeAddedMessage(value.ProtoReflect()) {
			return false
		}
		typed.Value, err = (proto.MarshalOptions{Deterministic: true}).Marshal(value)
		return err == nil
	}
	valid := true
	m.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case fd.IsMap() && fd.MapValue().Message() != nil:
			value.Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				valid = normalizeAddedMessage(v.Message())
				return valid
			})
		case fd.IsList() && fd.Message() != nil:
			list := value.List()
			for i := 0; i < list.Len() && valid; i++ {
				valid = normalizeAddedMessage(list.Get(i).Message())
			}
		case !fd.IsMap() && fd.Message() != nil:
			valid = normalizeAddedMessage(value.Message())
		}
		return valid
	})
	return valid
}
