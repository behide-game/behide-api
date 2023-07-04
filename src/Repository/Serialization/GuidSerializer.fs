namespace BehideApi.Serialization.Serializers

open System
open MongoDB.Bson.Serialization.Serializers

type GuidSerializer() =
    inherit SerializerBase<Guid>()
    override _.Deserialize(context, _args): Guid = context.Reader.ReadBytes() |> Guid
    override _.Serialize(context, _args, value) = value.ToByteArray() |> context.Writer.WriteBytes