#!/usr/bin/env python
u"""
api.py
Written by Tyler Sutterley (04/2024)
Plotting tools for visualizing geopandas geodataframes on leaflet maps

PYTHON DEPENDENCIES:
    geopandas: Python tools for geographic data
        http://geopandas.readthedocs.io/
    ipywidgets: interactive HTML widgets for Jupyter notebooks and IPython
        https://ipywidgets.readthedocs.io/en/latest/
    ipyleaflet: Jupyter / Leaflet bridge enabling interactive maps
        https://github.com/jupyter-widgets/ipyleaflet
    matplotlib: Python 2D plotting library
        http://matplotlib.org/
        https://github.com/matplotlib/matplotlib
    numpy: Scientific Computing Tools For Python
        https://numpy.org
        https://numpy.org/doc/stable/user/numpy-for-matlab-users.html

UPDATE HISTORY:
    Written 04/2024
"""

import io
import copy
import logging
import numpy as np
import collections.abc
import geopandas as gpd
import matplotlib.lines
import matplotlib.cm as cm
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.colors as colors
from traitlets.utils.bunch import Bunch

# imports that raise error if not present
try:
    import ipywidgets
except ModuleNotFoundError as e:
    logging.debug("ipywidgets not available")

# imports that raise error if not present
try:
    import ipyleaflet
except ModuleNotFoundError as e:
    logging.debug("ipyleaflet not available")

projection = dict(
    name='EPSG:3413',
    custom=True,
    proj4def="""+proj=stere +lat_0=90 +lat_ts=70 +lon_0=-45 +k=1 +x_0=0 +y_0=0
            +ellps=WGS84 +datum=WGS84 +units=m +no_defs""",
    origin=[-4194304, 4194304],
    resolutions=[
        16384.0,
        8192.0,
        4096.0,
        2048.0,
        1024.0,
        512.0,
        256.0,
        128.0,
        64.0,
        32.0,
        16.0,
        8.0,
        4.0,
        2.0,
        1.0
    ],
    bounds=[
        [-4194304, -4194304],
        [4194304, 4194304]
    ]
)

# define background ipyleaflet layers
layers = Bunch(
    PGC = Bunch(
        ArcticDEM = ipyleaflet.ImageService(
        name="ArcticDEM",
        attribution="""Esri, PGC, UMN, NSF, NGA, DigitalGlobe""",
        format='jpgpng',
        transparent=True,
        url='https://elevation2.arcgis.com/arcgis/rest/services/Polar/ArcticDEM/ImageServer',
        crs=projection
        )
    )
)

# draw ipyleaflet map
class Leaflet:
    def __init__(self, **kwargs):
        # set default keyword arguments
        kwargs.setdefault('prefer_canvas', True)
        kwargs.setdefault('attribution', False)
        kwargs.setdefault('scale_control', True)
        kwargs.setdefault('full_screen_control', True)
        kwargs.setdefault('cursor_control', True)
        kwargs.setdefault('layer_control', True)
        # create basemap in projection
        kwargs.setdefault('center', (72.5, -45))
        kwargs.setdefault('zoom', 2)
        self.map = ipyleaflet.Map(center=kwargs['center'],
            zoom=kwargs['zoom'], max_zoom=15,
            prefer_canvas=kwargs['prefer_canvas'],
            attribution_control=kwargs['attribution'],
            basemap=ipyleaflet.basemaps.NASAGIBS.BlueMarble3413,
            crs=projection)
        self.crs = 'EPSG:3413'
        # add control for full screen
        if kwargs['full_screen_control']:
            self.full_screen_control = ipyleaflet.FullScreenControl()
            self.map.add(self.full_screen_control)
        # add control for layers
        if kwargs['layer_control']:
            self.layer_control = ipyleaflet.LayersControl(position='topleft')
            self.map.add(self.layer_control)
            self.layers = self.map.layers
        # add control for spatial scale bar
        if kwargs['scale_control']:
            scale_control = ipyleaflet.ScaleControl(position='topright')
            self.map.add(scale_control)
        # add control for cursor position
        if kwargs['cursor_control']:
            self.cursor = ipywidgets.Label()
            cursor_control = ipyleaflet.WidgetControl(widget=self.cursor,
                position='bottomleft')
            self.map.add(cursor_control)
            # keep track of cursor position
            self.map.on_interaction(self.handle_interaction)

    def wrap_longitudes(self, lon):
        phi = np.arctan2(np.sin(lon*np.pi/180.0),np.cos(lon*np.pi/180.0))
        # convert phi from radians to degrees
        return phi*180.0/np.pi

    # handle cursor movements for label
    def handle_interaction(self, **kwargs):
        """callback for handling mouse motion and setting location label
        """
        if (kwargs.get('type') == 'mousemove'):
            lat,lon = kwargs.get('coordinates')
            lon = self.wrap_longitudes(lon)
            self.cursor.value = u"""Latitude: {d[0]:8.4f}\u00B0,
                Longitude: {d[1]:8.4f}\u00B0""".format(d=[lat,lon])

    def add(self, obj):
        """wrapper function for adding layers and controls to leaflet maps
        """
        if isinstance(obj, collections.abc.Iterable):
            for o in obj:
                try:
                    self.map.add(o)
                except ipyleaflet.LayerException as exc:
                    logging.info(f"{o} already on map")
                    pass
                except ipyleaflet.ControlException as exc:
                    logging.info(f"{o} already on map")
                    pass
        else:
            try:
                self.map.add(obj)
            except ipyleaflet.LayerException as exc:
                logging.info(f"{obj} already on map")
                pass
            except ipyleaflet.ControlException as exc:
                logging.info(f"{obj} already on map")
                pass

    def remove(self, obj):
        """wrapper function for removing layers and controls to leaflet maps
        """
        if isinstance(obj, collections.abc.Iterable):
            for o in obj:
                try:
                    self.map.remove(o)
                except ipyleaflet.LayerException as exc:
                    logging.info(f"{o} already removed from map")
                    pass
                except ipyleaflet.ControlException as exc:
                    logging.info(f"{o} already removed from map")
                    pass
        else:
            try:
                self.map.remove(obj)
            except ipyleaflet.LayerException as exc:
                logging.info(f"{obj} already removed from map")
                pass
            except ipyleaflet.ControlException as exc:
                logging.info(f"{obj} already removed from map")
                pass

@gpd.pd.api.extensions.register_dataframe_accessor("leaflet")
class LeafletMap:
    """A geopandas GeoDataFrame extension for interactive map plotting,
    based on ipyleaflet
    """

    def __init__(self, gdf):
        # initialize map
        self.map = None
        self.crs = None
        # initialize geodataframe
        self._gdf = gdf
        # initialize data 
        self.geojson = None
        self.tooltip = None
        self.tooltip_width = None
        self.tooltip_height = None
        self.fields = []
        # initialize hover control
        self.hover_control = None
        # initialize selected feature
        self.selected_callback = None

    # add geodataframe data to leaflet map
    def GeoData(self, m, **kwargs):
        """Creates scatter plots of GeoDataFrames on leaflet maps

        Parameters
        ----------
        m : obj, leaflet object
        column_name : str, GeoDataFrame column to plot
        cmap : str, matplotlib colormap
        tooltip : bool, show hover tooltips
        fields : list, GeoDataFrame fields to show in hover tooltips
        """
        kwargs.setdefault('column_name', 'SourceDate')
        kwargs.setdefault('cmap', 'viridis')
        kwargs.setdefault('tooltip', True)
        kwargs.setdefault('tooltip_height', "190px")
        kwargs.setdefault('tooltip_width', "290px")
        kwargs.setdefault('fields', None)
        kwargs.setdefault('position', 'topright')
        # set map and map coordinate reference system
        self.map = m
        self.crs = m.crs['name']
        # remove any prior instances of a data layer
        if self.geojson is not None:
            self.map.remove(self.geojson)
        # sliced geodataframe for plotting
        geodataframe = self._gdf
        self.column_name = copy.copy(kwargs['column_name'])
        if (self.column_name == 'SourceDate'):
            asdate = geodataframe[self.column_name].astype('datetime64[s]')
            geodataframe['data'] = asdate.astype(int)
        else:
            geodataframe['data'] = geodataframe[self.column_name]
        # set color limits
        vmin = geodataframe['data'].min()
        vmax = geodataframe['data'].max()
        # create matplotlib normalization
        norm = colors.Normalize(vmin=vmin, vmax=vmax, clip=True)
        # normalize data to be within vmin and vmax
        normalized = norm(geodataframe['data'])
        # create HEX colors for each point in the dataframe
        geodataframe["color"] = np.apply_along_axis(colors.to_hex, 1,
            cm.get_cmap(kwargs['cmap'], 256)(normalized))
        # convert to GeoJSON object
        self.geojson = ipyleaflet.GeoJSON(data=geodataframe.__geo_interface__,
            style_callback=self.style_callback)
        # add GeoJSON object to map
        self.map.add(self.geojson)
        # fields for tooltip views
        if kwargs['fields'] is None:
            self.fields = geodataframe.columns.drop(
                [geodataframe.geometry.name, "data", "color"])
        else:
            self.fields = copy.copy(kwargs['fields'])
        # add hover tooltips
        if kwargs['tooltip']:
            self.tooltip = ipywidgets.HTML()
            self.tooltip.layout.margin = "0px 20px 20px 20px"
            self.tooltip.layout.visibility = 'hidden'
            self.tooltip_height = kwargs['tooltip_height']
            self.tooltip_width = kwargs['tooltip_width']
            # create widget for hover tooltips
            self.hover_control = ipyleaflet.WidgetControl(
                widget=self.tooltip,
                position='bottomright')
            self.geojson.on_hover(self.handle_hover)
            self.geojson.on_msg(self.handle_mouseout)

    # functional call for setting colors of each point
    def style_callback(self, feature):
        """callback for setting marker colors
        """
        return {
            "fillColor": feature["properties"]["color"],
            "color": feature["properties"]["color"],
        }

    # functional calls for hover events
    def handle_hover(self, feature, **kwargs):
        """callback for creating hover tooltips
        """
        # combine html strings for hover tooltip
        self.tooltip.value = '<b>{0}:</b> {1}<br>'.format('id',feature['id'])
        self.tooltip.value += '<br>'.join(['<b>{0}:</b> {1}'.format(field,
            feature["properties"][field]) for field in self.fields])
        self.tooltip.layout.width = self.tooltip_width
        self.tooltip.layout.height = self.tooltip_height
        self.tooltip.layout.visibility = 'visible'
        self.map.add(self.hover_control)

    def handle_mouseout(self, _, content, buffers):
        """callback for removing hover tooltips upon mouseout
        """
        event_type = content.get('type', '')
        if event_type == 'mouseout':
            self.tooltip.value = ''
            self.tooltip.layout.width = "0px"
            self.tooltip.layout.height = "0px"
            self.tooltip.layout.visibility = 'hidden'
            self.map.remove(self.hover_control)
