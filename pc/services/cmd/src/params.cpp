#include "params.h"
using namespace OHOS::SignatureTools;
std::string Params::GetMethod()
{
    return method;
}
void Params::SetMethod(const std::string& method)
{
    this->method = method;
}
Options* Params::GetOptions()
{
    return options.get();
}
std::string Params::ToString()
{
    std::string destStr;
    destStr.append("Params{ method: ");
    destStr.append(method);
    destStr.append(", params: ");
    for (const auto& item : *GetOptions()) {
        destStr.append("-");
        destStr.append(item.first);
        destStr.append("=");
        destStr.append(std::visit(VariantToString{}, item.second));
        destStr.append(";");
    }
    destStr.append("}");
    return destStr;
}