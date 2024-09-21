from rest_framework.renderers import JSONRenderer

class SuccessJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        if renderer_context["response"].status_code >= 400:
            if 'non_field_errors' in data:
                data['message'] = data.pop('non_field_errors')
                data["success"] = False

        if not renderer_context["response"].exception:
            if renderer_context["response"].status_code not in [200, 201, 204]:
                data["success"] = False
            else:
                data["success"] = True
        return super(SuccessJSONRenderer, self).render(data, accepted_media_type, renderer_context)

