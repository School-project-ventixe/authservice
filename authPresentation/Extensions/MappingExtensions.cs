using System.Reflection;

namespace authPresentation.Extensions;

public static class MappingExtensions
{
    public static TDestination MapTo<TDestination>(this object source)
    {
        ArgumentNullException.ThrowIfNull(source);

        var destination = (TDestination)Activator.CreateInstance(typeof(TDestination))!;

        var srcType = source.GetType();
        var dstType = typeof(TDestination);
        var srcProps = srcType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var dstProps = dstType.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        foreach (var dstProp in dstProps)
        {
            if (!dstProp.CanWrite)
                continue;

            var direct = srcProps.FirstOrDefault(p =>
                p.Name == dstProp.Name && p.PropertyType == dstProp.PropertyType);

            if (direct != null)
            {
                dstProp.SetValue(destination, direct.GetValue(source));
                continue;
            }


            var nav = srcProps.FirstOrDefault(p =>
                !p.PropertyType.IsValueType &&
                p.PropertyType != typeof(string) &&
                p.PropertyType.GetProperty(dstProp.Name) != null);

            if (nav == null)
                continue;

            var parentObj = nav.GetValue(source);
            if (parentObj == null)
                continue;

            var nestedVal = nav.PropertyType
                               .GetProperty(dstProp.Name)!
                               .GetValue(parentObj);
            dstProp.SetValue(destination, nestedVal);
        }

        return destination;
    }
}