/* Generic replacing blitter (slow).  Works for every supported format.  */
static void
SUFFIX(grub_video_fbblit_replace) (struct grub_video_fbblit_info *dst,
				   struct grub_video_fbblit_info *src,
				   int x, int y, int width, int height,
				   int offset_x, int offset_y)
{
  int i;
  int j;
  grub_uint8_t src_red;
  grub_uint8_t src_green;
  grub_uint8_t src_blue;
  grub_uint8_t src_alpha;
  grub_video_color_t src_color;
  grub_video_color_t dst_color;

  for (j = 0; j < height; j++)
    {
      for (i = 0; i < width; i++)
	{
	  src_color = get_pixel (src, i + offset_x, j + offset_y);

	  grub_video_fb_unmap_color_int (src, src_color, &src_red, &src_green,
					 &src_blue, &src_alpha);

	  dst_color = grub_video_fb_map_rgba (src_red, src_green,
					      src_blue, src_alpha);

	  set_pixel (dst, x + TRANS_X(i, j), y + TRANS_Y(i, j), dst_color);
	}
    }
}

/* Generic blending blitter.  Works for every supported format.  */
static void
SUFFIX(grub_video_fbblit_blend) (struct grub_video_fbblit_info *dst,
				 struct grub_video_fbblit_info *src,
				 int x, int y, int width, int height,
				 int offset_x, int offset_y)
{
  int i;
  int j;

  for (j = 0; j < height; j++)
    {
      for (i = 0; i < width; i++)
        {
          grub_uint8_t src_red;
          grub_uint8_t src_green;
          grub_uint8_t src_blue;
          grub_uint8_t src_alpha;
          grub_uint8_t dst_red;
          grub_uint8_t dst_green;
          grub_uint8_t dst_blue;
          grub_uint8_t dst_alpha;
          grub_video_color_t src_color;
          grub_video_color_t dst_color;

          src_color = get_pixel (src, i + offset_x, j + offset_y);
          grub_video_fb_unmap_color_int (src, src_color, &src_red, &src_green,
					 &src_blue, &src_alpha);

          if (src_alpha == 0)
            continue;

          if (src_alpha == 255)
            {
              dst_color = grub_video_fb_map_rgba (src_red, src_green,
						  src_blue, src_alpha);
              set_pixel (dst, x + TRANS_X(i, j), y + TRANS_Y(i, j), dst_color);
              continue;
            }

          dst_color = get_pixel (dst, x + TRANS_X(i, j), y + TRANS_Y(i, j));

          grub_video_fb_unmap_color_int (dst, dst_color, &dst_red,
					 &dst_green, &dst_blue, &dst_alpha);

          dst_red = alpha_dilute (dst_red, src_red, src_alpha);
          dst_green = alpha_dilute (dst_green, src_green, src_alpha);
          dst_blue = alpha_dilute (dst_blue, src_blue, src_alpha);

          dst_alpha = src_alpha;
          dst_color = grub_video_fb_map_rgba (dst_red, dst_green, dst_blue,
					      dst_alpha);

          set_pixel (dst, x + TRANS_X(i, j), y + TRANS_Y(i, j), dst_color);
        }
    }
}

#undef SUFFIX
#undef ADD_X
#undef ADD_Y
#undef TRANS_X
#undef TRANS_Y
