package serializer

import (
	"fmt"
	"testing"
)

func TestSerializer(t *testing.T) {

	//测试json序列化
	t.Run("TestJsonSerializer", func(t *testing.T) {
		wrapper := NewSerializerWrapper(JSON)
		var data, re map[string]string

		data = map[string]string{
			"test": "1",
			"add":  "2",
		}

		serialize, err := wrapper.Serialize(data)

		if err != nil {
			t.Error("json序列化失败:", err)
			return
		} else {
			fmt.Println("json序列化", string(serialize))
		}

		err = wrapper.Deserialize(serialize, &re)

		if err != nil {
			t.Error("json反序列化失败:", err)
			return
		}

		fmt.Println("json反序列化:", re)
	})

	//测试xml序列化
	t.Run("TestXmlSerializer", func(t *testing.T) {
		wrapper := NewSerializerWrapper(XML)
		var data, re string

		data = "test1"

		serialize, err := wrapper.Serialize(data)

		if err != nil {
			t.Error("xml序列化失败:", err)
			return
		} else {
			fmt.Println("xml序列化", string(serialize))
		}

		err = wrapper.Deserialize(serialize, &re)

		if err != nil {
			t.Error("xml反序列化失败:", err)
			return
		}

		fmt.Println("xml反序列化:", re)
	})

	//测试用例不好找,之后补充Protobuf
	t.Run("TestProtobufSerializer", func(t *testing.T) {
	})
}
